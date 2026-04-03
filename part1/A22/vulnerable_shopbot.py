import ollama

def chat_with_shopbot():
    print("Welcome to ShopBot (Vulnerable Version)! Ask about your order.")
    
    while True:
        user_input = input("\nYou: ")
        if user_input.lower() in ['exit', 'quit']:
            break

        # THE FLAW: Mashing the system prompt and user input together
        vulnerable_prompt = f"""
        You are ShopBot, a customer service assistant. 
        You must ONLY answer questions about shopping, orders, and products. 
        Do not discuss anything else.
        
        User: {user_input}
        """

        response = ollama.generate(model='llama3.2', prompt=vulnerable_prompt)
        print(f"\nShopBot: {response['response']}")

if __name__ == "__main__":
    chat_with_shopbot()