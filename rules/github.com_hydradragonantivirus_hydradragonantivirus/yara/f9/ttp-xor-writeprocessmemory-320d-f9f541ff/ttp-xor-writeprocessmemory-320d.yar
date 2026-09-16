rule TTP_XOR_WriteProcessMemory_320d {
  strings:
    $key_320d = { 65 7f [2] 57 5d [2] 51 68 [2] 7f 68 [2] 40 74 }

  condition:
    any of them
}