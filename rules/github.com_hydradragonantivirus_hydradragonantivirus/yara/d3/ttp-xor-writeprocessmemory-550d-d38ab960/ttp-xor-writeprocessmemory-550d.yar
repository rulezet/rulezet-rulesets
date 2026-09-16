rule TTP_XOR_WriteProcessMemory_550d {
  strings:
    $key_550d = { 02 7f [2] 30 5d [2] 36 68 [2] 18 68 [2] 27 74 }

  condition:
    any of them
}