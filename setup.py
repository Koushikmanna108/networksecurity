'''
The setup.py file is an essential part of packaging and 
distributing Python projects. It is used by setuptools
to define the configuration of our project such as 
metadata, dependencies and more.
'''


from setuptools import find_packages, setup
from typing import List

def get_requirements()->List[str]:
    '''
    This Function will return list of requirements
    '''
    requirement_list:list[str]=[]
    try:
        with open('requirements.txt','r') as file:
            # Read lines from the file
            lines = file.readlines()
            # Process each line
            for line in lines:
                requirement = line.strip()
                # ignore empty lines and -e .
                if requirement and requirement != '-e .':
                    requirement_list.append(requirement)

    except FileNotFoundError:
        print("requirements.txt file not found")
    
    return requirement_list


setup (
    name = "Network Security",
    version = "0.0.1",
    author = "Koushik Manna",
    author_email = "kmanna713@gmail.com",
    packages = find_packages(),
    install_requires = get_requirements()
)

