from setuptools import setup, find_packages

setup(
    name="ida_raiversing",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "openai>=1.0.0",
        "rich>=13.0.0",
        "requests>=2.31.0",
        "python-dotenv>=1.0.0",
        "tqdm>=4.66.0"
    ],
    author="Your Name",
    author_email="your.email@example.com",
    description="AI-powered reverse engineering assistant for IDA Pro",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    python_requires=">=3.7",
)
