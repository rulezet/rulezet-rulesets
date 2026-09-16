rule TTP_XOR_WriteProcessMemory_210d {
  strings:
    $key_210d = { 76 7f [2] 44 5d [2] 42 68 [2] 6c 68 [2] 53 74 }

  condition:
    any of them
}