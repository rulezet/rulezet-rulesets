rule eval_post {
    strings:
        $ = "eval(base64_decode($_POST"
        $ = "eval($undecode($tongji))"
        $ = "eval($_POST"
    condition: any of them
}