import threading
import socket
import time
import json
from collections import deque, defaultdict
from flask import Flask, render_template_string, jsonify
from datetime import datetime

app = Flask(__name__)

class TrafficStats:
    def __init__(self):
        self.http_requests = 0
        self.udp_packets = 0
        self.tcp_connections = 0
        self.udp_bytes = 0
        self.tcp_bytes = 0
        self.http_bytes = 0
        self.total_bytes = 0
        self.start_time = time.time()
        
        self.packet_history = deque(maxlen=100)
        self.bandwidth_history = deque(maxlen=100)
        self.tcp_bandwidth_history = deque(maxlen=100)
        self.udp_bandwidth_history = deque(maxlen=100)
        self.http_bandwidth_history = deque(maxlen=100)
        
        self.current_second_packets = 0
        self.current_second_bytes = 0
        self.current_second_tcp_bytes = 0
        self.current_second_udp_bytes = 0
        self.current_second_http_bytes = 0
        self.last_second = int(time.time())

stats = TrafficStats()

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>idom dstat</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: #000000;
            color: #e0e0e0; min-height: 100vh; padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { text-align: center; margin-bottom: 30px; }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; text-shadow: 2px 2px 4px rgba(0,0,0,0.8); }
        .copy-buttons { display: flex; gap: 10px; justify-content: center; margin: 20px 0; flex-wrap: wrap; }
        .copy-btn { 
            background: rgba(20,20,20,0.9); border: 1px solid #333; color: #fff; 
            padding: 8px 16px; border-radius: 8px; cursor: pointer; font-size: 14px;
            transition: all 0.3s ease; backdrop-filter: blur(10px);
        }
        .copy-btn:hover { background: rgba(0,255,136,0.2); border-color: #00ff88; }
        .copy-btn:active { transform: scale(0.95); }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { 
            background: rgba(15,15,15,0.95); backdrop-filter: blur(10px); 
            border-radius: 15px; padding: 20px; border: 1px solid #222;
            box-shadow: 0 8px 32px rgba(0,0,0,0.8);
        }
        .stat-card h3 { color: #ffd700; margin-bottom: 15px; font-size: 1.2em; }
        .stat-value { font-size: 2em; font-weight: bold; color: #00ff88; }
        .stat-label { font-size: 0.9em; color: #999; margin-top: 5px; }
        .charts-container { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }
        .protocol-charts { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .chart-container { 
            background: rgba(15,15,15,0.95); backdrop-filter: blur(10px); 
            border-radius: 15px; padding: 20px; border: 1px solid #222;
            height: 400px;
        }
        .live-indicator { 
            display: inline-block; width: 10px; height: 10px; 
            background: #00ff88; border-radius: 50%; 
            animation: pulse 1s infinite; margin-right: 10px;
        }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
        .uptime { color: #ffd700; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><span class="live-indicator"></span>idom dstat</h1>
        </div>
        
        <div class="copy-buttons">
            <button class="copy-btn" onclick="copyToClipboard('127.0.0.1')">Copy IP</button>
            <button class="copy-btn" onclick="copyToClipboard('53')">Copy UDP Port</button>
            <button class="copy-btn" onclick="copyToClipboard('22')">Copy TCP Port</button>
            <button class="copy-btn" onclick="copyToClipboard('8080')">Copy HTTP Port</button>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Traffic</h3>
                <div class="stat-value" id="total-traffic">0 B</div>
                <div class="stat-label">All protocols combined</div>
            </div>
            <div class="stat-card">
                <h3>Current Traffic</h3>
                <div class="stat-value" id="current-traffic">0 B/s</div>
                <div class="stat-label">Real-time data rate</div>
            </div>
            <div class="stat-card">
                <h3>Average Traffic</h3>
                <div class="stat-value" id="avg-traffic">0 B/s</div>
                <div class="stat-label">Since start</div>
            </div>
            <div class="stat-card">
                <h3>Packets/Second</h3>
                <div class="stat-value" id="packets-per-sec">0</div>
                <div class="stat-label">Current packet rate</div>
            </div>
            <div class="stat-card">
                <h3>HTTP Requests</h3>
                <div class="stat-value" id="http-requests">0</div>
                <div class="stat-label">Total HTTP requests</div>
            </div>
            <div class="stat-card">
                <h3>Uptime</h3>
                <div class="stat-value uptime" id="uptime">0s</div>
                <div class="stat-label">Monitor running time</div>
            </div>
        </div>

        <div class="charts-container">
            <div class="chart-container">
                <canvas id="trafficChart"></canvas>
            </div>
            <div class="chart-container">
                <canvas id="bandwidthChart"></canvas>
            </div>
        </div>

        <div class="protocol-charts">
            <div class="chart-container">
                <canvas id="tcpChart"></canvas>
            </div>
            <div class="chart-container">
                <canvas id="udpChart"></canvas>
            </div>
            <div class="chart-container">
                <canvas id="httpChart"></canvas>
            </div>
        </div>
    </div>

    <script>
        let charts = {};

        function formatBytes(bytes) {
            if (bytes >= 1099511627776) return (bytes / 1099511627776).toFixed(2) + ' TB';
            if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(2) + ' GB';
            if (bytes >= 1048576) return (bytes / 1048576).toFixed(2) + ' MB';
            if (bytes >= 1024) return (bytes / 1024).toFixed(2) + ' KB';
            return bytes + ' B';
        }

        function formatUptime(seconds) {
            const hrs = Math.floor(seconds / 3600);
            const mins = Math.floor((seconds % 3600) / 60);
            const secs = Math.floor(seconds % 60);
            return `${hrs}h ${mins}m ${secs}s`;
        }

        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                const btn = event.target;
                const originalText = btn.textContent;
                btn.textContent = 'Copied!';
                btn.style.background = 'rgba(0,255,136,0.3)';
                setTimeout(() => {
                    btn.textContent = originalText;
                    btn.style.background = 'rgba(20,20,20,0.9)';
                }, 1000);
            });
        }

        function initCharts() {
            const commonOptions = {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { labels: { color: '#e0e0e0' } }
                },
                scales: {
                    x: { ticks: { color: '#777' }, grid: { color: 'rgba(119,119,119,0.1)' } },
                    y: { ticks: { color: '#777' }, grid: { color: 'rgba(119,119,119,0.1)' } }
                },
                animation: { duration: 200 }
            };

            charts.traffic = new Chart(document.getElementById('trafficChart').getContext('2d'), {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [
                        {
                            label: 'HTTP Packets',
                            data: [],
                            borderColor: '#ff6b6b',
                            backgroundColor: 'rgba(255, 107, 107, 0.1)',
                            tension: 0.4
                        },
                        {
                            label: 'UDP Packets',
                            data: [],
                            borderColor: '#4ecdc4',
                            backgroundColor: 'rgba(78, 205, 196, 0.1)',
                            tension: 0.4
                        },
                        {
                            label: 'TCP Packets',
                            data: [],
                            borderColor: '#45b7d1',
                            backgroundColor: 'rgba(69, 183, 209, 0.1)',
                            tension: 0.4
                        }
                    ]
                },
                options: {
                    ...commonOptions,
                    plugins: {
                        ...commonOptions.plugins,
                        title: { display: true, text: 'Live Packet Traffic', color: '#e0e0e0' }
                    }
                }
            });

            charts.bandwidth = new Chart(document.getElementById('bandwidthChart').getContext('2d'), {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Bandwidth',
                        data: [],
                        borderColor: '#ffd700',
                        backgroundColor: 'rgba(255, 215, 0, 0.1)',
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: {
                    ...commonOptions,
                    plugins: {
                        ...commonOptions.plugins,
                        title: { display: true, text: 'Live Bandwidth Usage', color: '#e0e0e0' }
                    },
                    scales: {
                        ...commonOptions.scales,
                        y: { 
                            ...commonOptions.scales.y,
                            ticks: {
                                ...commonOptions.scales.y.ticks,
                                callback: function(value) {
                                    return formatBytes(value) + '/s';
                                }
                            }
                        }
                    }
                }
            });

            charts.tcp = new Chart(document.getElementById('tcpChart').getContext('2d'), {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'TCP Bandwidth',
                        data: [],
                        borderColor: '#45b7d1',
                        backgroundColor: 'rgba(69, 183, 209, 0.1)',
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: {
                    ...commonOptions,
                    plugins: {
                        ...commonOptions.plugins,
                        title: { display: true, text: 'TCP Bandwidth (Port 22)', color: '#e0e0e0' }
                    },
                    scales: {
                        ...commonOptions.scales,
                        y: { 
                            ...commonOptions.scales.y,
                            ticks: {
                                ...commonOptions.scales.y.ticks,
                                callback: function(value) {
                                    return formatBytes(value) + '/s';
                                }
                            }
                        }
                    }
                }
            });

            charts.udp = new Chart(document.getElementById('udpChart').getContext('2d'), {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'UDP Bandwidth',
                        data: [],
                        borderColor: '#4ecdc4',
                        backgroundColor: 'rgba(78, 205, 196, 0.1)',
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: {
                    ...commonOptions,
                    plugins: {
                        ...commonOptions.plugins,
                        title: { display: true, text: 'UDP Bandwidth (Port 53)', color: '#e0e0e0' }
                    },
                    scales: {
                        ...commonOptions.scales,
                        y: { 
                            ...commonOptions.scales.y,
                            ticks: {
                                ...commonOptions.scales.y.ticks,
                                callback: function(value) {
                                    return formatBytes(value) + '/s';
                                }
                            }
                        }
                    }
                }
            });

            charts.http = new Chart(document.getElementById('httpChart').getContext('2d'), {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'HTTP Bandwidth',
                        data: [],
                        borderColor: '#ff6b6b',
                        backgroundColor: 'rgba(255, 107, 107, 0.1)',
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: {
                    ...commonOptions,
                    plugins: {
                        ...commonOptions.plugins,
                        title: { display: true, text: 'HTTP Bandwidth (Port 8080)', color: '#e0e0e0' }
                    },
                    scales: {
                        ...commonOptions.scales,
                        y: { 
                            ...commonOptions.scales.y,
                            ticks: {
                                ...commonOptions.scales.y.ticks,
                                callback: function(value) {
                                    return formatBytes(value) + '/s';
                                }
                            }
                        }
                    }
                }
            });
        }

        function updateChart(chart, data) {
            const now = new Date().toLocaleTimeString();
            chart.data.labels.push(now);
            
            if (chart.data.datasets.length === 1) {
                chart.data.datasets[0].data.push(data);
            } else {
                chart.data.datasets[0].data.push(data.http || 0);
                chart.data.datasets[1].data.push(data.udp || 0);
                chart.data.datasets[2].data.push(data.tcp || 0);
            }

            if (chart.data.labels.length > 50) {
                chart.data.labels.shift();
                chart.data.datasets.forEach(dataset => dataset.data.shift());
            }
            
            chart.update('none');
        }

        function updateStats() {
            fetch('/api/stats')
                .then(response => {
                    if (!response.ok) throw new Error('Network error');
                    return response.json();
                })
                .then(data => {
                    document.getElementById('total-traffic').textContent = formatBytes(data.total_bytes);
                    document.getElementById('current-traffic').textContent = formatBytes(data.current_bandwidth) + '/s';
                    document.getElementById('packets-per-sec').textContent = data.packets_per_second;
                    document.getElementById('avg-traffic').textContent = formatBytes(data.avg_bandwidth) + '/s';
                    document.getElementById('http-requests').textContent = data.total_http_requests;
                    document.getElementById('uptime').textContent = formatUptime(data.uptime);

                    updateChart(charts.traffic, {
                        http: data.http_packets_current,
                        udp: data.udp_packets_current,
                        tcp: data.tcp_packets_current
                    });
                    
                    updateChart(charts.bandwidth, data.current_bandwidth);
                    updateChart(charts.tcp, data.tcp_bandwidth);
                    updateChart(charts.udp, data.udp_bandwidth);
                    updateChart(charts.http, data.http_bandwidth);
                })
                .catch(error => console.error('Error updating stats:', error));
        }

        document.addEventListener('DOMContentLoaded', function() {
            initCharts();
            updateStats();
            setInterval(updateStats, 1000);
        });
    </script>
</body>
</html>
'''

@app.route('/')
def dashboard():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/stats')
def api_stats():
    current_time = int(time.time())
    uptime = time.time() - stats.start_time
    
    if current_time != stats.last_second:
        stats.packet_history.append(stats.current_second_packets)
        stats.bandwidth_history.append(stats.current_second_bytes)
        stats.tcp_bandwidth_history.append(stats.current_second_tcp_bytes)
        stats.udp_bandwidth_history.append(stats.current_second_udp_bytes)
        stats.http_bandwidth_history.append(stats.current_second_http_bytes)
        stats.current_second_packets = 0
        stats.current_second_bytes = 0
        stats.current_second_tcp_bytes = 0
        stats.current_second_udp_bytes = 0
        stats.current_second_http_bytes = 0
        stats.last_second = current_time
    
    avg_bandwidth = stats.total_bytes / uptime if uptime > 0 else 0
    current_bandwidth = stats.bandwidth_history[-1] if stats.bandwidth_history else 0
    tcp_bandwidth = stats.tcp_bandwidth_history[-1] if stats.tcp_bandwidth_history else 0
    udp_bandwidth = stats.udp_bandwidth_history[-1] if stats.udp_bandwidth_history else 0
    http_bandwidth = stats.http_bandwidth_history[-1] if stats.http_bandwidth_history else 0
    packets_per_second = stats.packet_history[-1] if stats.packet_history else 0
    
    return jsonify({
        'total_bytes': stats.total_bytes,
        'current_bandwidth': current_bandwidth,
        'avg_bandwidth': avg_bandwidth,
        'packets_per_second': packets_per_second,
        'total_http_requests': stats.http_requests,
        'uptime': uptime,
        'http_packets_current': 0,
        'udp_packets_current': stats.udp_packets,
        'tcp_packets_current': stats.tcp_connections,
        'tcp_bandwidth': tcp_bandwidth,
        'udp_bandwidth': udp_bandwidth,
        'http_bandwidth': http_bandwidth
    })

def update_traffic_stats(bytes_count, protocol='general'):
    stats.total_bytes += bytes_count
    stats.current_second_bytes += bytes_count
    stats.current_second_packets += 1
    
    if protocol == 'tcp':
        stats.current_second_tcp_bytes += bytes_count
    elif protocol == 'udp':
        stats.current_second_udp_bytes += bytes_count
    elif protocol == 'http':
        stats.current_second_http_bytes += bytes_count

def run_flask():
    app.run(host="0.0.0.0", port=8080, debug=False, use_reloader=False, threaded=True)

def udp_listener():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", 53))
        print("[UDP] Listening on port 53...")
        
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                stats.udp_packets += 1
                stats.udp_bytes += len(data)
                update_traffic_stats(len(data), 'udp')
            except Exception as e:
                continue
                
    except Exception as e:
        print(f"[UDP] Could not bind to port 53: {e}")

def tcp_listener():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", 22))
        sock.listen(5)
        print("[TCP] Listening on port 22...")

        while True:
            try:
                conn, addr = sock.accept()
                stats.tcp_connections += 1
                threading.Thread(target=handle_tcp_connection, args=(conn,), daemon=True).start()
            except Exception as e:
                continue
                
    except Exception as e:
        print(f"[TCP] Could not bind to port 22: {e}")

def handle_tcp_connection(conn):
    try:
        with conn:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                stats.tcp_bytes += len(data)
                update_traffic_stats(len(data), 'tcp')
    except Exception as e:
        pass

@app.before_request
def count_http():
    stats.http_requests += 1
    stats.current_second_packets += 1
    estimated_request_size = 1024
    stats.http_bytes += estimated_request_size
    update_traffic_stats(estimated_request_size, 'http')

if __name__ == "__main__":
    print("[*] Starting idom dstat")
    print("[*] Web Dashboard: http://0.0.0.0:8080")
    print("[*] Monitoring UDP port: 53")
    print("[*] Monitoring TCP port: 22") 
    print("[*] HTTP Dashboard on port: 8080")

    # Start UDP and TCP listeners in the background
    threading.Thread(target=udp_listener, daemon=True).start()
    threading.Thread(target=tcp_listener, daemon=True).start()

    # Start Flask on 0.0.0.0 to allow external access
    app.run(host="0.0.0.0", port=8080)

