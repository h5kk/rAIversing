from setuptools import setup, find_packages

setup(
    name="standalone_raiversing",
    version="1.0.0",
    description="Standalone AI-powered reverse engineering tool for IDA Pro databases",
    author="rAIversing Team",
    packages=find_packages(),
    install_requires=[
        'openai>=1.0.0',
        'tiktoken>=0.5.0',
        'typing-extensions>=4.0.0'
    ],
    python_requires='>=3.6',
    entry_points={
        'console_scripts': [
            'raiversing=raiversing_core:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'Topic :: Software Development :: Disassemblers',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
    ],
) 