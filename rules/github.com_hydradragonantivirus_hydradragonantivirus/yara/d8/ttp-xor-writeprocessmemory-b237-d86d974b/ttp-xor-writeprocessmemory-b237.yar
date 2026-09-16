rule TTP_XOR_WriteProcessMemory_b237 {
  strings:
    $key_b237 = { e5 45 [2] d7 67 [2] d1 52 [2] ff 52 [2] c0 4e }

  condition:
    any of them
}