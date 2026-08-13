from setuptools import find_packages, setup

setup(
    name="sentinelmail",
    version="0.1.0",
    description="Evidence-driven email security intelligence for authorized investigations.",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31",
        "dnspython>=2.4",
        "click>=8.1",
        "rich>=13.0",
    ],
    entry_points={
        "console_scripts": [
            "sentinelmail=sentinelmail.cli:main",
        ],
    },
    python_requires=">=3.9",
)
