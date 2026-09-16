rule TTP_XOR_WriteProcessMemory_88ed {
  strings:
    $key_88ed = { df 9f [2] ed bd [2] eb 88 [2] c5 88 [2] fa 94 }

  condition:
    any of them
}