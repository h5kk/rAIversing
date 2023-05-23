import json
import multiprocessing
import random
import string
import threading
import time
from inspect import getframeinfo, stack

from rAIversing.AI_modules.openAI_core import chatGPT
from rAIversing.pathing import *
import multiprocessing as mp

class MaxTriesExceeded(Exception):
    """Raised when the max tries is exceeded"""


class NoResponseException(Exception):
    """Raised when no response is received"""


class InvalidResponseException(Exception):
    """Raised when the response is invalid"""


def ptr_escape(string):
    rand_str = get_random_string(5)
    return string.replace("PTR_FUN_", rand_str)


def check_and_fix_bin_path(binary_path):
    if os.path.isfile(os.path.abspath(binary_path)):
        return os.path.abspath(binary_path)
    else:
        if os.path.isfile(os.path.join(BINARIES_ROOT, binary_path)):
            return os.path.join(BINARIES_ROOT, binary_path)
        else:
            raise FileNotFoundError(f"Binary {binary_path} not found in {BINARIES_ROOT}")


def check_and_fix_project_path(project_path):
    if os.path.isdir(os.path.abspath(project_path)):
        return os.path.abspath(project_path)
    else:
        if os.path.isdir(os.path.join(PROJECTS_ROOT, project_path)):
            return os.path.join(PROJECTS_ROOT, project_path)
        else:
            raise NotADirectoryError(f"Project {project_path} not found in {PROJECTS_ROOT}")


def check_and_create_project_path(project_path):
    if not os.path.isdir(project_path):
        os.mkdir(project_path)


def extract_function_name(code):
    if "WARNING: Removing unreachable block (ram," in code:
        code = code.split("\n\n")[1].split("(")[0].split("\n")[-1].split(" ")[-1]
        return code

    return code.split("(")[0].split(" ")[-1]


def generate_function_name(code, name):
    new_name = f"{extract_function_name(code).replace('FUN_', '')}_{name.replace('FUN_', '')}"
    return code.replace(extract_function_name(code), new_name), new_name

def check_reverse_engineer_fail_happend(code):
    # returns true if the code contains reverse and engineer (in the case that the model called it reverse_engineered_function)
    code=extract_function_name(code)
    if "reverse" in code.lower() and "engineer" in code.lower():
        return True
    else:
        return False


def check_and_fix_double_function_renaming(code, renaming_dict, name):
    if name in renaming_dict.keys():
        present_name = extract_function_name(code)
        if present_name != renaming_dict[name]:
            if present_name not in renaming_dict[name]:
                # print(f"Replacing {present_name} with {renaming_dict[name]} in {name}")
                pass
            code = code.replace(present_name, renaming_dict[name])
    return code


def is_already_exported(project_location, binary_name):
    if os.path.isfile(os.path.join(project_location, f"{binary_name.replace('.', '_')}.json")):
        return True
    else:
        #print(f"""File {os.path.join(project_location, f'{binary_name.replace(".", "_")}.json')} not found""")
        return False


def get_random_string(length):
    # choose from all lowercase letter
    letters = string.ascii_uppercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str


def check_do_nothing(code):
    code = "{" + code.split("{")[1].split("}")[0] + "}"
    code = code.replace(" ", "").replace("\n", "").rstrip().strip()
    if "{return;}" == code:
        return True
    else:
        return False


def clear_extra_data(response, e):
    # Extra data: line 8 column 1 (char 177)
    # remove everything after char 177 from response
    last_del = 0
    while last_del != int(e.split("char ")[1].split(")")[0]):
        last_del = int(e.split("char ")[1].split(")")[0])
        response = response[:last_del]
        try:
            response_dict = json.loads(response, strict=False)
            return response_dict
        except json.decoder.JSONDecodeError as a:
            e = str(a)


def split_response(response_dict):
    renaming_dict = {}
    response_string = ""
    if len(response_dict) == 2:
        for key in response_dict:
            if "code" in key:
                improved_code = response_dict[key]
            else:
                if type(response_dict[key]) == dict:
                    for old, new in response_dict[key].items():
                        renaming_dict[old] = new
                elif type(response_dict[key]) == list:
                    for entry in response_dict[key]:
                        for old, new in entry.items():
                            renaming_dict[old] = new

    elif len(response_dict) == 3:
        for key in response_dict:
            if "code" in key or "Code" in key:
                improved_code = response_dict[key]
            elif "old" in key:
                old_key = key
            elif "new" in key:
                new_key = key
            else:
                raise InvalidResponseException("Invalid response format")
        if type(response_dict[old_key]) == list and type(response_dict[new_key]) == list:
            for old, new in zip(response_dict[old_key], response_dict[new_key]):
                renaming_dict[old] = new
        elif type(response_dict[old_key]) == dict and response_dict[new_key] == response_dict[old_key]:
            renaming_dict = response_dict[old_key]

    elif len(response_dict) == 1:
        print(response_dict)
        raise Exception("Only one Key in response dict")

    return improved_code, renaming_dict


def check_valid_code(code):
    if "{" not in code or "}" not in code or "(" not in code or ")" not in code:
        return False
    else:
        return True


def format_newlines_in_code(code):
    front = code.split('improved_code": "')[0]
    main = code.split('improved_code": "')[1].split('}",')[0]
    back = code.split('improved_code": "')[1].split('}",')[1]
    main = main.replace('\\', '\\\\')
    main = main.replace('\n', '\\n')
    main = main.replace('"', '\\"')
    main = main.replace('\'', '\\"')

    return front + 'improved_code": "' + main + '}\",' + back

def escape_failed_escapes(response_string):
    #original = response_string
    response_string = response_string.replace("\'\\x", "\'\\\\x")

    return response_string


def prompt_parallel(ai_module,result_queue,name,code,retries):
    try:
        #print(f"Starting {name}")
        result= ai_module.prompt_with_renaming(code, retries)
        result_queue.put((name,result))
    except KeyboardInterrupt:
        return


    except Exception as e:
        print(f"Error in {name}: {e}\n")
        result_queue.put((name, "SKIP"))

def locator(context=False):
    caller = getframeinfo(stack()[1][0])
    if context:
        return f"{caller.filename}:{caller.lineno} - {caller.code_context}"
    else:
        return f"{caller.filename}:{caller.lineno}"

def prompt_dispatcher(args, total, self, result_queue):
    started = 0
    processes = []

    for arg in args:
        p = mp.Process(target=prompt_parallel, args=arg)
        p.start()
        processes.append(p)
        started += 1

    results_dict = {}
    while len(results_dict) < len(args):
        name, result = result_queue.get()
        results_dict[name] = result
        current_cost = self.ai_module.calc_used_tokens(self.ai_module.assemble_prompt(self.functions[name]["code"]))
        self.console.print(
            f"{len(results_dict)}/{total} | Improving function [blue]{name}[/blue] for {current_cost} Tokens | Used tokens: {self.used_tokens}")
        self.used_tokens += current_cost
    for p in processes:
        p.join()
        p.close()
    return results_dict


def handle_spawn_worker(processes, prompting_args, started):
    if len(prompting_args) > 0:
        p = mp.Process(target=prompt_parallel, args=prompting_args.pop(0))
        p.start()
        processes.append(p)
        started += 1


def load_funcs_from_json(file,return_lfl=False):
    """
    if file is not a path to a file, it is assumed to be relative to PROJECTS_ROOT
    :param file:
    """
    if not os.path.exists(file):
        file = os.path.join(PROJECTS_ROOT,file)
    with open(file, "r") as f:
        save_file = json.load(f)
        if "functions" in save_file.keys():
            functions = save_file["functions"]
            if return_lfl:
                return functions, save_file["layers"][0]
        else:
            functions = save_file
    return functions

def save_to_json(data, file):
    """
    if file is not a path to an existing file, it is assumed to be relative to PROJECTS_ROOT
    :param data:
    :param file:
    """
    if not os.path.exists(file):
        file = os.path.join(PROJECTS_ROOT,file)
    with open(file, "w") as f:
        json.dump(data, f, indent=4)