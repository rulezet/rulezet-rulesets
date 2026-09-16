rule RhadamanthysQ3VM {
  meta:
    author      = "Daniel Mayer (daniel@stairwell.com)"
    description = "Detects q3vm embedded in executables - used by Rhadamanthys"
    version     = "1.0"
    date        = "2023-03-03"
    source1     = "https://www.zscaler.com/blogs/security-research/technical-analysis-rhadamanthys-obfuscation-techniques"
    source2     = "https://raw.githubusercontent.com/jnz/q3vm/master/src/vm/vm.c"

  strings:
    $BEEF     = {
      C7 45 00 EF BE 00 00      }
    $DISPATCH = {
      0F B6 CB           8D 53 FF           0F B6 C2           8B 44 85 00        8D 74 8D 00      }
    $OP_NEGI  = {
      0F B6 D3           F7 D9              89 4C 95 00      }
    $OP_ADD   = {
      FE CB              03 C1              0F B6 CB           89 44 8D 00      }
    $OP_MODI  = {
      99                 FE CB              F7 F9              0F B6 C3           89 54 85 00      }
    $OP_BXOR  = {
      FE CB              0F B6 D3           33 C1              89 44 95 00      }

  condition:
    ($BEEF or $DISPATCH) and 3 of ($OP*)
}