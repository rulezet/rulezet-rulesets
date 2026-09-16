rule TTP_XOR_WriteProcessMemory_8815 {
  strings:
    $key_8815 = { df 67 [2] ed 45 [2] eb 70 [2] c5 70 [2] fa 6c }

  condition:
    any of them
}