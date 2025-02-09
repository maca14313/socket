<?php
header('Access-Control-Allow-Origin: http://localhost:5173'); // Specific to your frontend's port
header('Content-Type: application/json');
header("Access-Control-Allow-Methods: GET, POST, OPTIONS"); 
header("Access-Control-Allow-Headers: Content-Type, Authorization");

require 'vendor/autoload.php';

use Ratchet\MessageComponentInterface;
use Ratchet\ConnectionInterface;

class SignalingServer implements MessageComponentInterface {
    protected $clients = [];
    protected $peerIds = [];

    public function onOpen(ConnectionInterface $conn) {
        $query = $conn->httpRequest->getUri()->getQuery();
        parse_str($query, $queryParams);

        if (isset($queryParams['peerId'])) {
            $peerId = $queryParams['peerId'];
            $this->clients[$peerId] = $conn;
            $this->peerIds[] = $peerId;
            echo "Peer Connected: $peerId\n";
            $this->broadcastPeerList();
        }
    }

    public function onMessage(ConnectionInterface $from, $msg) {
        $data = json_decode($msg, true);

        // Handle new stream notifications
        if (isset($data['type']) && $data['type'] === 'new_stream') {
            $this->broadcastNewStream($data['peerId']);
        }

        // Forward the messages from one client to the target
        if (isset($data['target']) && isset($this->clients[$data['target']])) {
            $this->clients[$data['target']]->send(json_encode($data));
        }
    }

    public function onClose(ConnectionInterface $conn) {
        foreach ($this->clients as $peerId => $client) {
            if ($client === $conn) {
                unset($this->clients[$peerId]);
                $this->peerIds = array_values(array_diff($this->peerIds, [$peerId]));
                echo "Peer Disconnected: $peerId\n";
                break;
            }
        }
        $this->broadcastPeerList();
    }

    public function onError(ConnectionInterface $conn, \Exception $e) {
        echo "Error: " . $e->getMessage() . "\n";
        $conn->close();
    }

    private function broadcastPeerList() {
        $data = json_encode(["peers" => $this->peerIds]);
        foreach ($this->clients as $client) {
            $client->send($data);
        }
    }

    private function broadcastNewStream($peerId) {
        // Broadcast the new stream availability to all connected clients
        $data = json_encode(["type" => "new_stream", "peerId" => $peerId]);
        foreach ($this->clients as $client) {
            $client->send($data);
        }
    }
}

use Ratchet\Server\IoServer;
use Ratchet\Http\HttpServer;
use Ratchet\WebSocket\WsServer;

$server = IoServer::factory(
    new HttpServer(
        new WsServer(
            new SignalingServer()
        )
    ),
    8080
);

echo "WebSocket Signaling Server is running on ws://localhost:8080\n";
$server->run();
?>
