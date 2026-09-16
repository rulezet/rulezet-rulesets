rule TTP_XOR_WriteProcessMemory_627d {
  strings:
    $key_627d = { 35 0f [2] 07 2d [2] 01 18 [2] 2f 18 [2] 10 04 }

  condition:
    any of them
}