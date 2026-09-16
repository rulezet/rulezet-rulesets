rule TTP_XOR_WriteProcessMemory_a305 {
  strings:
    $key_a305 = { f4 77 [2] c6 55 [2] c0 60 [2] ee 60 [2] d1 7c }

  condition:
    any of them
}