rule libavcodec_COOK_cplscale3__flt64___64_big_56_ {
  strings:
    $a0 = { 3f ef 66 a4 e0 00 00 02 3f ed fb e2 5f ff ff fe 3f ec 07 a7 c0 00 00 04 3f e6 a0 9e 5f ff ff fc 3f de e0 22 3f ff ff fc 3f d6 5b 84 9f ff ff fa 3f c8 a6 b4 df ff ff ee }

  condition:
    $a0
}