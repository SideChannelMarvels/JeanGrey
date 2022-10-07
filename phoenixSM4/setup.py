import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="phoenixSM4",
    version="0.0.1",
    author="Sylvain Pelissier",
    author_email="sylvain.pelissier@gmail.com",
    description="tool to perform differential fault analysis attacks (DFA) against SM4",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/SideChannelMarvels/JeanGrey",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Science/Research",
        "Topic :: Security :: Cryptography",
    ],
)
