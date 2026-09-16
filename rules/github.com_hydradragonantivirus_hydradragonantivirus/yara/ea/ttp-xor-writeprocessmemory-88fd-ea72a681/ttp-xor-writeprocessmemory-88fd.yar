rule TTP_XOR_WriteProcessMemory_88fd {
  strings:
    $key_88fd = { df 8f [2] ed ad [2] eb 98 [2] c5 98 [2] fa 84 }

  condition:
    any of them
}