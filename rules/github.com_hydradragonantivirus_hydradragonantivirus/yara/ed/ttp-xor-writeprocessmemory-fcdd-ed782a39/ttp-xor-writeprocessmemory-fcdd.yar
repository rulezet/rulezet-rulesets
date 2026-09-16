rule TTP_XOR_WriteProcessMemory_fcdd {
  strings:
    $key_fcdd = { ab af [2] 99 8d [2] 9f b8 [2] b1 b8 [2] 8e a4 }

  condition:
    any of them
}