rule TTP_XOR_WriteProcessMemory_a0fa {
  strings:
    $key_a0fa = { f7 88 [2] c5 aa [2] c3 9f [2] ed 9f [2] d2 83 }

  condition:
    any of them
}