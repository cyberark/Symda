# Symda

![GitHub release](https://img.shields.io/badge/version-1.0-blue)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://choosealicense.com/licenses/mit/)
## Overview

Symda is an open-source tool designed as a helper tool for Frida.
The tool aims to download and parse symbol files for a given executable. The symbol server the script uses can be configured, and by default, it uses the Microsoft public symbol server.

Note - this tool is designed only for Windows executables. 

---

## Usage

1. Change the FUNCTION_LIST variable according to your needs inside symda_python_runner.py .
For example:
```python
...
FUNCTION_LIST = [
    "KERNELBASE!DeviceIoControl",
]
...
```

2. Run the following command with the relevant pid

```bash
python symda_python_runner.py <PID>
```

## License
Copyright (c) 2022 CyberArk Software Ltd. All rights reserved  
This repository is licensed under MIT License - see [`LICENSE`](LICENSE) for more details.

## References:

For comments, suggestions, or questions, you can contact Omer Tsarfati ([@OmerTsarfati](https://twitter.com/OmerTsarfati)) and CyberArk Labs team.
You can find more projects developed by us at https://github.com/cyberark/.
