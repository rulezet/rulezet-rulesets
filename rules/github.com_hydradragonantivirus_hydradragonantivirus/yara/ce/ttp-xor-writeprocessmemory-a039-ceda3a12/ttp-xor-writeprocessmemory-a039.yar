rule TTP_XOR_WriteProcessMemory_a039 {
  strings:
    $key_a039 = { f7 4b [2] c5 69 [2] c3 5c [2] ed 5c [2] d2 40 }

  condition:
    any of them
}