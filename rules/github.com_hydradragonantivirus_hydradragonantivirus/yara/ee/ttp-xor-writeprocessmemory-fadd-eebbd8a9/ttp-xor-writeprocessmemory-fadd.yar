rule TTP_XOR_WriteProcessMemory_fadd {
  strings:
    $key_fadd = { ad af [2] 9f 8d [2] 99 b8 [2] b7 b8 [2] 88 a4 }

  condition:
    any of them
}