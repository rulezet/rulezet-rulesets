rule TTP_XOR_WriteProcessMemory_dedc {
  strings:
    $key_dedc = { 89 ae [2] bb 8c [2] bd b9 [2] 93 b9 [2] ac a5 }

  condition:
    any of them
}