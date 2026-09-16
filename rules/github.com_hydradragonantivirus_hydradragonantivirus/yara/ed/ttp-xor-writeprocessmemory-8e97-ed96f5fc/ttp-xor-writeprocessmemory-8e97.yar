rule TTP_XOR_WriteProcessMemory_8e97 {
  strings:
    $key_8e97 = { d9 e5 [2] eb c7 [2] ed f2 [2] c3 f2 [2] fc ee }

  condition:
    any of them
}