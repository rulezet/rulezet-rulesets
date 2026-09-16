rule TTP_XOR_WriteProcessMemory_d7ea {
  strings:
    $key_d7ea = { 80 98 [2] b2 ba [2] b4 8f [2] 9a 8f [2] a5 93 }

  condition:
    any of them
}