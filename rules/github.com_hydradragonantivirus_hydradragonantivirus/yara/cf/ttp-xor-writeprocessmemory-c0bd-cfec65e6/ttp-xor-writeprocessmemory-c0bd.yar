rule TTP_XOR_WriteProcessMemory_c0bd {
  strings:
    $key_c0bd = { 97 cf [2] a5 ed [2] a3 d8 [2] 8d d8 [2] b2 c4 }

  condition:
    any of them
}