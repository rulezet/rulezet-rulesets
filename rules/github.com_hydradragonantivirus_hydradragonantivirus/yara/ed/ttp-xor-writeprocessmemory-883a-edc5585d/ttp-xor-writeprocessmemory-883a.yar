rule TTP_XOR_WriteProcessMemory_883a {
  strings:
    $key_883a = { df 48 [2] ed 6a [2] eb 5f [2] c5 5f [2] fa 43 }

  condition:
    any of them
}