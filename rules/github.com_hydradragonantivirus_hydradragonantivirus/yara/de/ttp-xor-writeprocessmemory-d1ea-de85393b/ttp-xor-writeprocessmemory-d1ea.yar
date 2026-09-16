rule TTP_XOR_WriteProcessMemory_d1ea {
  strings:
    $key_d1ea = { 86 98 [2] b4 ba [2] b2 8f [2] 9c 8f [2] a3 93 }

  condition:
    any of them
}