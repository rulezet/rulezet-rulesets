rule TTP_XOR_WriteProcessMemory_a06a {
  strings:
    $key_a06a = { f7 18 [2] c5 3a [2] c3 0f [2] ed 0f [2] d2 13 }

  condition:
    any of them
}