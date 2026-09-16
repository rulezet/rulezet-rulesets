rule TTP_XOR_WriteProcessMemory_481b {
  strings:
    $key_481b = { 1f 69 [2] 2d 4b [2] 2b 7e [2] 05 7e [2] 3a 62 }

  condition:
    any of them
}