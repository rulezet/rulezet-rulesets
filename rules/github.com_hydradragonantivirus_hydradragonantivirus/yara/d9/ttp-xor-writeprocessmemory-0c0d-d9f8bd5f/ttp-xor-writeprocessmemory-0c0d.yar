rule TTP_XOR_WriteProcessMemory_0c0d {
  strings:
    $key_0c0d = { 5b 7f [2] 69 5d [2] 6f 68 [2] 41 68 [2] 7e 74 }

  condition:
    any of them
}