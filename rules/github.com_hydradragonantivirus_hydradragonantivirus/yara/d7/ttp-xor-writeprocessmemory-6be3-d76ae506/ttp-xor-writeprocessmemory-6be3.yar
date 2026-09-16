rule TTP_XOR_WriteProcessMemory_6be3 {
  strings:
    $key_6be3 = { 3c 91 [2] 0e b3 [2] 08 86 [2] 26 86 [2] 19 9a }

  condition:
    any of them
}