rule TTP_XOR_WriteProcessMemory_88eb {
  strings:
    $key_88eb = { df 99 [2] ed bb [2] eb 8e [2] c5 8e [2] fa 92 }

  condition:
    any of them
}