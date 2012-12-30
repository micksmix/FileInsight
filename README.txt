Plugin for McAfee FileInsight

* Embedded EXE Extract
  If you highlight the MZ header embedded in an exe (0x4D 0x5A),
  the script will calculate the length of the EXE from the PE header
  and copy it to a new file.

How to use:
Please copy plugin folders to %USERPROFILE%\Documents\FileInsight\plugins .
You need Python installed in addition to FileInsight.

Author: Mick Grove

License: The BSD 2-Clause License (http://opensource.org/licenses/bsd-license.php)

Thank you to Nobutaka Mantani for providing inspiration (and other plugins for FileInsight - https://github.com/nmantani/FileInsight-plugins)