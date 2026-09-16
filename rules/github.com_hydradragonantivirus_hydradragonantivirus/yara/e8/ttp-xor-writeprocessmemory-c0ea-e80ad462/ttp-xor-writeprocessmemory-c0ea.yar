rule TTP_XOR_WriteProcessMemory_c0ea {
  strings:
    $key_c0ea = { 97 98 [2] a5 ba [2] a3 8f [2] 8d 8f [2] b2 93 }

  condition:
    any of them
}