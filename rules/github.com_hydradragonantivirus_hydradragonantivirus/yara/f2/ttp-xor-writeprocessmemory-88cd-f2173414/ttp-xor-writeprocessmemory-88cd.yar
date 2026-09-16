rule TTP_XOR_WriteProcessMemory_88cd {
  strings:
    $key_88cd = { df bf [2] ed 9d [2] eb a8 [2] c5 a8 [2] fa b4 }

  condition:
    any of them
}