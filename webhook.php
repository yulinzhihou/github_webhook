<?php
/**
 * GitHub webhook handler template.
 *
 * @see  https://developer.github.com/webhooks/
 * @author  Miloslav Hůla (https://github.com/milo)
 * @author  Modify by  (https://github.com/yulinzhihou)
 */
$hookSecret = '123456';  # set NULL to disable check
$rawPost = NULL;
$dir = '';/*执行更新的目录*/
$devDir = '';/*表示项目的测试目录*/
$productDir = '';/*项目的生产目录*/
$backupDir = '';/*备份项目的目录*/

/*设置用户的函数 (error_handler) 来处理脚本中出现的错误*/
set_error_handler(function($severity, $message, $file, $line) {
    throw new \ErrorException($message, 0, $severity, $file, $line);
});

/*设置用户的函数 (set_exception_handler) 来处理脚本中出现的异常*/
set_exception_handler(function($e) {
    header('HTTP/1.1 500 Internal Server Error');
    echo "Error on line {$e->getLine()}: " . htmlSpecialChars($e->getMessage());
    die();
});

/*判断webhook secret密码是否为空，并得出相应的hash值*/
if ($hookSecret !== NULL) {
    if (!isset($_SERVER['HTTP_X_HUB_SIGNATURE'])) {
        throw new \Exception("HTTP header 'X-Hub-Signature' is missing.");
    } elseif (!extension_loaded('hash')) {
        throw new \Exception("Missing 'hash' extension to check the secret code validity.");
    }
    list($algo, $hash) = explode('=', $_SERVER['HTTP_X_HUB_SIGNATURE'], 2) + array('', '');
    if (!in_array($algo, hash_algos(), TRUE)) {
        throw new \Exception("Hash algorithm '$algo' is not supported.");
    }
    $rawPost = file_get_contents('php://input');
    if ($hash !== hash_hmac($algo, $rawPost, $hookSecret)) {
        throw new \Exception('Hook secret does not match.');
    }
};
/*判断*/
if (!isset($_SERVER['HTTP_CONTENT_TYPE'])) {
    throw new \Exception("Missing HTTP 'Content-Type' header.");
} elseif (!isset($_SERVER['HTTP_X_GITHUB_EVENT'])) {
    throw new \Exception("Missing HTTP 'X-Github-Event' header.");
}

switch ($_SERVER['HTTP_CONTENT_TYPE']) {
    case 'application/json':
        $json = $rawPost ?: file_get_contents('php://input');
        break;
    case 'application/x-www-form-urlencoded':
        $json = $_POST['payload'];
        break;
    default:
        throw new \Exception("Unsupported content type: $_SERVER[HTTP_CONTENT_TYPE]");
}
# Payload structure depends on triggered event
# https://developer.github.com/v3/activity/events/types/
$payload = json_decode($json);

switch (strtolower($_SERVER['HTTP_X_GITHUB_EVENT'])) {
    case 'ping':
        echo 'ping';
        break;
    case 'push':
        /*推送事件的处理*/
        echo 'push';
        $ref = $payload->ref;
        if (strrpos($ref, 'master') !== false ) {
            //表示是master分支，也就是生产环境，利用一台电脑上不可能同时存在生产环境和测试环境来自动更新
            if (file_exists($productDir)) {
                echo shell_exec("cd {$productDir}  && git pull origin master 2>&1");
            }
        } else {
            //表示develop分支，也就是测试分支,利用一台电脑上不可能同时存在生产环境和测试环境来自动更新
            if (file_exists($devDir)) {
                echo shell_exec("cd {$devDir}  && git pull origin develop 2>&1");
            }
        }
        //print_r($payload); # For debug only. Can be found in GitHub hook log.
        break;
	case 'create':
	    echo 'create';
		break;
    default:
        header('HTTP/1.0 404 Not Found');
        echo "Event:$_SERVER[HTTP_X_GITHUB_EVENT] Payload:\n";
        print_r($payload); # For debug only. Can be found in GitHub hook log.
        die();
}
