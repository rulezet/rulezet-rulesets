rule TTP_XOR_WriteProcessMemory_b214 {
  strings:
    $key_b214 = { e5 66 [2] d7 44 [2] d1 71 [2] ff 71 [2] c0 6d }

  condition:
    any of them
}