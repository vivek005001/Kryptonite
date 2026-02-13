from setuptools import setup, find_packages

setup(
    name="kryptonite",
    version="1.0.0",
    packages=find_packages(),
    install_requires=["lxml>=4.9", "jinja2>=3.1"],
    entry_points={"console_scripts": ["kryptonite=kryptonite.cli:main"]},
    include_package_data=True,
    package_data={"kryptonite": ["reports/template.html"]},
)
