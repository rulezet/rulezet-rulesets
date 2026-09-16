rule TTP_XOR_WriteProcessMemory_a4cd {
  strings:
    $key_a4cd = { f3 bf [2] c1 9d [2] c7 a8 [2] e9 a8 [2] d6 b4 }

  condition:
    any of them
}