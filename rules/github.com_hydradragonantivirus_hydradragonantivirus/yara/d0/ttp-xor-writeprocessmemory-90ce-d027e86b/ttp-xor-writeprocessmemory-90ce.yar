rule TTP_XOR_WriteProcessMemory_90ce {
  strings:
    $key_90ce = { c7 bc [2] f5 9e [2] f3 ab [2] dd ab [2] e2 b7 }

  condition:
    any of them
}