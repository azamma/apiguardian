#!/usr/bin/env python3
"""
Setup script for API Guardian
"""

from pathlib import Path
from setuptools import setup, find_packages


# Read long description from README
readme_file = Path(__file__).parent / "README.md"
long_description = ""
if readme_file.exists():
    with open(readme_file, "r", encoding="utf-8") as fh:
        long_description = fh.read()
else:
    long_description = "Automated AWS API Gateway Security Auditor"

setup(
    name="api-guardian",
    version="1.0.0",
    author="API Guardian Team",
    description="Automated AWS API Gateway Security Auditor",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/api-guardian",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7+",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "Topic :: System :: Monitoring",
        "Topic :: Security",
    ],
    python_requires=">=3.7",
    entry_points={
        "console_scripts": [
            "apiguardian=apiguardian.apiguardian:main",
        ],
    },
    include_package_data=True,
    package_data={
        "apiguardian": ["whitelist.json"],
    },
)
