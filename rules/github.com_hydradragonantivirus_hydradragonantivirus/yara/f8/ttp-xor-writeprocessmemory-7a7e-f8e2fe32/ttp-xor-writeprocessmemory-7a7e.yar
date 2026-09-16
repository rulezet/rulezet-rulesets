rule TTP_XOR_WriteProcessMemory_7a7e {
  strings:
    $key_7a7e = { 2d 0c [2] 1f 2e [2] 19 1b [2] 37 1b [2] 08 07 }

  condition:
    any of them
}