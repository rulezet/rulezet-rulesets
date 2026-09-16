rule TTP_XOR_WriteProcessMemory_280d {
  strings:
    $key_280d = { 7f 7f [2] 4d 5d [2] 4b 68 [2] 65 68 [2] 5a 74 }

  condition:
    any of them
}