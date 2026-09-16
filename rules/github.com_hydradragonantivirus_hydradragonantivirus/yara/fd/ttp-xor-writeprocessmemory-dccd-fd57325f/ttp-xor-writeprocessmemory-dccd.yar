rule TTP_XOR_WriteProcessMemory_dccd {
  strings:
    $key_dccd = { 8b bf [2] b9 9d [2] bf a8 [2] 91 a8 [2] ae b4 }

  condition:
    any of them
}