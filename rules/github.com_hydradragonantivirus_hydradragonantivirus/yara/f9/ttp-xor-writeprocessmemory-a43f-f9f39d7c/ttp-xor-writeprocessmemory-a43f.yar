rule TTP_XOR_WriteProcessMemory_a43f {
  strings:
    $key_a43f = { f3 4d [2] c1 6f [2] c7 5a [2] e9 5a [2] d6 46 }

  condition:
    any of them
}