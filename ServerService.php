<?php
// 路径:/app/Services/ServerService.php
// 适用版本1.2.5正式版
namespace App\Services;


use App\Models\User;
use App\Models\Server;

class ServerService
{

    CONST SERVER_CONFIG = '{"api":{"services":["HandlerService","StatsService"],"tag":"api"},"dns":{},"stats":{},"inbound":{"port":443,"protocol":"vmess","settings":{"clients":[]},"sniffing":{"enabled":true,"destOverride":["http","tls"]},"streamSettings":{"network":"tcp"},"tag":"proxy"},"inboundDetour":[{"listen":"0.0.0.0","port":23333,"protocol":"dokodemo-door","settings":{"address":"0.0.0.0"},"tag":"api"}],"log":{"loglevel":"debug","access":"access.log","error":"error.log"},"outbound":{"protocol":"freedom","settings":{}},"outboundDetour":[{"protocol":"blackhole","settings":{},"tag":"block"}],"routing":{"rules":[{"inboundTag":"api","outboundTag":"api","type":"field"}]},"policy":{"levels":{"0":{"handshake":4,"connIdle":300,"uplinkOnly":5,"downlinkOnly":30,"statsUserUplink":true,"statsUserDownlink":true}}}}';

    public function getAvailableUsers($groupId)
    {
        return User::whereIn('group_id', $groupId)
            ->whereRaw('u + d < transfer_enable')
            ->where(function ($query) {
                $query->where('expired_at', '>=', time())
                    ->orWhere('expired_at', NULL);
            })
            ->where('banned', 0)
            ->select([
                'id',
                'email',
                't',
                'u',
                'd',
                'transfer_enable',
                'v2ray_uuid',
                'v2ray_alter_id',
                'v2ray_level'
            ])
            ->get();
    }

    public function getConfig(int $nodeId, int $localPort)
    {
        $server = Server::find($nodeId);
        if (!$server) {
            abort(500, '节点不存在');
        }
        $json = json_decode(self::SERVER_CONFIG);
        $json->inboundDetour[0]->port = (int)$localPort;
        $json->inbound->port = (int)$server->server_port;
        $json->inbound->streamSettings->network = $server->network;
        $this->setDns($server, $json);
        $this->setNetwork($server, $json);
        $this->setRule($server, $json);
        $this->setTls($server, $json);

        return $json;
    }

    private function setDns(Server $server, object $json)
    {
        if ($server->dnsSettings) {
            $dns = json_decode($server->dnsSettings);
            $json->dns = $dns;
            $json->outbound->settings->domainStrategy = 'UseIP';
        }
    }

    private function setNetwork(Server $server, object $json)
    {
        if ($server->networkSettings) {
            switch ($server->network) {
                case 'tcp':
                    $json->inbound->streamSettings->tcpSettings = json_decode($server->networkSettings);
                    break;
                case 'kcp':
                    $json->inbound->streamSettings->kcpSettings = json_decode($server->networkSettings);
                    break;
                case 'ws':
                    $json->inbound->streamSettings->wsSettings = json_decode($server->networkSettings);
                    break;
                case 'http':
                    $json->inbound->streamSettings->httpSettings = json_decode($server->networkSettings);
                    break;
                case 'domainsocket':
                    $json->inbound->streamSettings->dsSettings = json_decode($server->networkSettings);
                    break;
                case 'quic':
                    $json->inbound->streamSettings->quicSettings = json_decode($server->networkSettings);
                    break;
            }
        }
    }

    private function setRule(Server $server, object $json)
    {
    // 更改开始
    //全局节点屏蔽规则
            $rulesAll = ["domain:epochtimes.com","domain:epochtimes.com.tw","domain:epochtimes.fr","domain:epochtimes.de","domain:epochtimes.jp","domain:epochtimes.ru","domain:epochtimes.co.il","domain:epochtimes.co.kr","domain:epochtimes-romania.com","domain:erabaru.net","domain:lagranepoca.com","domain:theepochtimes.com","domain:ntdtv.com","domain:ntd.tv","domain:ntdtv-dc.com","domain:ntdtv.com.tw","domain:minghui.org","domain:renminbao.com","domain:dafahao.com","domain:dongtaiwang.com","domain:falundafa.org","domain:wujieliulan.com","domain:ninecommentaries.com","domain:360.cn","domain:360.com","domain:so.com","domain:so.cn","domain:lbsyun.baidu.com","domain:api.map.baidu.com","domain:xunlei.com","mycard520.com","mycard520.tw","mycard.com","sandai.com","Thunder.com"];
            // domain
        if ($server->ruleSettings) {
            $rules = json_decode($server->ruleSettings);
            // domain
            if (isset($rules->domain) && !empty($rules->domain)) {
                $domainObj = new \StdClass();
                $domainObj->type = 'field';
                $rulesAdds = array_merge($rulesAll, $rules->domain);
                $domainObj->domain = $rulesAdds;
                $domainObj->outboundTag = 'block';
                array_push($json->routing->rules, $domainObj);
            }
            // protocol
            if (isset($rules->protocol) && !empty($rules->protocol)) {
                $protocolObj = new \StdClass();
                $protocolObj->type = 'field';
                $protocolObj->protocol = $rules->protocol;
                $protocolObj->outboundTag = 'block';
                array_push($json->routing->rules, $protocolObj);
            }
        }else {
                $domainObj = new \StdClass();
                $domainObj->type = 'field';
                $domainObj->domain = $rulesAll;
                $domainObj->outboundTag = 'block';
                array_push($json->routing->rules, $domainObj);
            }
    }
    // 更改结束

    private function setTls(Server $server, object $json)
    {
        if ((int)$server->tls) {
            $tlsSettings = json_decode($server->tlsSettings);
            $json->inbound->streamSettings->security = 'tls';
            $tls = (object)[
                'certificateFile' => '/home/v2ray.crt',
                'keyFile' => '/home/v2ray.key'
            ];
            $json->inbound->streamSettings->tlsSettings = new \StdClass();
            if (isset($tlsSettings->serverName)) {
                $json->inbound->streamSettings->tlsSettings->serverName = (string)$tlsSettings->serverName;
            }
            if (isset($tlsSettings->allowInsecure)) {
                $json->inbound->streamSettings->tlsSettings->allowInsecure = (int)$tlsSettings->allowInsecure ? true : false;
            }
            $json->inbound->streamSettings->tlsSettings->certificates[0] = $tls;
        }
    }
}
