rule TTP_XOR_WriteProcessMemory_9f75 {
  strings:
    $key_9f75 = { c8 07 [2] fa 25 [2] fc 10 [2] d2 10 [2] ed 0c }

  condition:
    any of them
}