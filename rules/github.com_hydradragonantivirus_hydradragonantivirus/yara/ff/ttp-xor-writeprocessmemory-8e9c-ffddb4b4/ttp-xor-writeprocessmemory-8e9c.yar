rule TTP_XOR_WriteProcessMemory_8e9c {
  strings:
    $key_8e9c = { d9 ee [2] eb cc [2] ed f9 [2] c3 f9 [2] fc e5 }

  condition:
    any of them
}