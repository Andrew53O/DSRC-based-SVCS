import random
import time
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Generate RSA key pair
def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def sign_message(private_key, message):
    key = RSA.import_key(private_key)
    h = SHA256.new(message.encode('utf-8'))
    signature = pkcs1_15.new(key).sign(h)
    return signature

def verify_signature(public_key, message, signature):
    key = RSA.import_key(public_key)
    h = SHA256.new(message.encode('utf-8'))
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

class Simulation:
    def __init__(self, num_vehicles):
        self.num_vehicles = num_vehicles
        self.vehicles = {}
        self.messages_sent = 0
        self.messages_received = 0
        self.total_delay = 0
        self.start_time = None

        # Generate keys for vehicles
        for i in range(self.num_vehicles):
            private_key, public_key = generate_rsa_key_pair()
            self.vehicles[i] = {
                'private_key': private_key,
                'public_key': public_key
            }

    def send_message(self, vehicle_from, vehicle_to, message):
        private_key_from = self.vehicles[vehicle_from]['private_key']
        public_key_from = self.vehicles[vehicle_from]['public_key']
        public_key_to = self.vehicles[vehicle_to]['public_key']

        # Vehicle `vehicle_from` signs the message
        start_sign_time = time.time()
        signature = sign_message(private_key_from, message)
        sign_time = time.time() - start_sign_time

        # Vehicle `vehicle_to` verifies the message using `vehicle_from`'s public key
        start_verify_time = time.time()
        is_valid = verify_signature(public_key_from, message, signature)
        verify_time = time.time() - start_verify_time

        if is_valid:
            # Update performance metrics
            self.messages_received += 1
            self.total_delay += (time.time() - self.start_time)  # Calculate delay
            return True, sign_time, verify_time
        else:
            return False, sign_time, verify_time

    def simulate(self, num_messages):
        self.start_time = time.time()
        for _ in range(num_messages):
            # Select random vehicles for communication
            vehicle_a = random.randint(0, self.num_vehicles - 1)
            vehicle_b = random.randint(0, self.num_vehicles - 1)
            while vehicle_b == vehicle_a:
                vehicle_b = random.randint(0, self.num_vehicles - 1)

            message = f"Message from vehicle {vehicle_a} to vehicle {vehicle_b}"
            #print(f"Sending message: {message}")
            # Send message and record performance metrics
            success, sign_time, verify_time = self.send_message(vehicle_a, vehicle_b, message)
            if success:
                self.messages_sent += 1
                # Print sign and verify times for analysis
                #print(f"Sign Time: {sign_time}, Verify Time: {verify_time}")

    def get_packet_delivery_ratio(self):
        if self.messages_sent == 0:
            return 0
        else:
            return self.messages_received / self.messages_sent

    def get_average_delay(self):
        if self.messages_received == 0:
            return 0
        else:
            return self.total_delay / self.messages_received

    def get_throughput(self):
        if self.messages_sent == 0:
            return 0
        else:
            total_time = time.time() - self.start_time
            return self.messages_sent / total_time

# Example usage
sim = Simulation(num_vehicles=30)
num_messages = 20
sim.simulate(num_messages)

# Get performance metrics
pdr = sim.get_packet_delivery_ratio()
average_delay = sim.get_average_delay()
throughput = sim.get_throughput()

print(f"Packet Delivery Ratio: {pdr}")
print(f"Average Delay: {average_delay} seconds")
print(f"Throughput: {throughput} messages per second")
