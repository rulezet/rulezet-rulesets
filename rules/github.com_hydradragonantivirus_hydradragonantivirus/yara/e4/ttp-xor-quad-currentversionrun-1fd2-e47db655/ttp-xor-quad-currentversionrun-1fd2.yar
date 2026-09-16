rule TTP_XOR_QUAD_CurrentVersionRun_1fd2 {
  strings:
    $key_1fd2 = { 4c bd [2] 68 b3 [2] 43 9f [2] 6d bd [2] 79 a6 [2] 76 bc [2] 68 a1 [2] 6a a0 [2] 71 a6 [2] 6d a1 [2] 71 8e }

  condition:
    any of them
}