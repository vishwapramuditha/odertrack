import React, { useState, useEffect, useCallback } from 'react';
import { initializeApp } from 'firebase/app';
import {
    getFirestore,
    collection,
    addDoc,
    getDocs,
    query,
    where,
    doc,
    updateDoc,
    setDoc,
    deleteDoc,
    onSnapshot,
    Timestamp
} from 'firebase/firestore';
import {
    getAuth,
    signInAnonymously,
    onAuthStateChanged,
    signInWithCustomToken
} from 'firebase/auth';

const bcrypt = {
    hashSync: (password, salt) => {
        if (typeof window.bcrypt !== 'undefined') {
            return window.bcrypt.hashSync(password, window.bcrypt.genSaltSync(10));
        }
        console.warn("bcrypt.js not loaded. Using insecure password placeholder.");
        return `hashed_${password}`;
    },
    compareSync: (password, hash) => {
        if (typeof window.bcrypt !== 'undefined') {
            return window.bcrypt.compareSync(password, hash);
        }
        console.warn("bcrypt.js not loaded. Using insecure password comparison.");
        return `hashed_${password}` === hash;
    }
};

const firebaseConfig = typeof __firebase_config !== 'undefined' ? JSON.parse(__firebase_config) : {
    apiKey: "YOUR_API_KEY",
    authDomain: "YOUR_AUTH_DOMAIN",
    projectId: "YOUR_PROJECT_ID",
    storageBucket: "YOUR_STORAGE_BUCKET",
    messagingSenderId: "YOUR_MESSAGING_SENDER_ID",
    appId: "YOUR_APP_ID"
};

const app = initializeApp(firebaseConfig);
const db = getFirestore(app);
const auth = getAuth(app);

const appId = typeof __app_id !== 'undefined' ? __app_id : 'default-app-id';

const APP_CLIENTS_COLLECTION = `/artifacts/${appId}/public/data/appClients`;
const ORDERS_COLLECTION = `/artifacts/${appId}/public/data/orders`;

function App() {
    const [user, setUser] = useState(null);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState('');
    const [firebaseAuthUser, setFirebaseAuthUser] = useState(null);
    const [isAuthReady, setIsAuthReady] = useState(false);
    const [currentView, setCurrentView] = useState('login');

    useEffect(() => {
        const unsubscribe = onAuthStateChanged(auth, async (authUser) => {
            if (authUser) {
                setFirebaseAuthUser(authUser);
                console.log("Firebase user signed in:", authUser.uid);
            } else {
                setFirebaseAuthUser(null);
                console.log("Firebase user signed out or not available.");
                if (typeof __initial_auth_token === 'undefined') {
                    try {
                        await signInAnonymously(auth);
                        console.log("Signed in anonymously");
                    } catch (e) {
                        console.error("Anonymous sign-in failed:", e);
                        setError("Firebase authentication failed. Please refresh.");
                    }
                }
            }
            setIsAuthReady(true);
        });
        return () => unsubscribe();
    }, []);

    useEffect(() => {
        const signIn = async () => {
            if (typeof __initial_auth_token !== 'undefined' && __initial_auth_token && auth) {
                try {
                    await signInWithCustomToken(auth, __initial_auth_token);
                    console.log("Successfully signed in with custom token.");
                } catch (e) {
                    console.error("Custom token sign-in failed:", e);
                    setError("Firebase custom token authentication failed.");
                    if (!auth.currentUser) {
                        try {
                            await signInAnonymously(auth);
                            console.log("Signed in anonymously after custom token failure.");
                        } catch (anonError) {
                            console.error("Anonymous sign-in failed after custom token failure:", anonError);
                        }
                    }
                }
            } else if (!auth.currentUser && isAuthReady) {
                 try {
                    await signInAnonymously(auth);
                    console.log("Signed in anonymously (no custom token).");
                } catch (e) {
                    console.error("Anonymous sign-in failed (no custom token):", e);
                }
            }
            setIsLoading(false);
        };
        
        if(isAuthReady){
            signIn();
        }

    }, [isAuthReady]);


    const handleLogin = async (username, password) => {
        setError('');
        setIsLoading(true);
        if (!isAuthReady || !auth.currentUser) {
            setError("Firebase is not ready. Please wait or refresh.");
            setIsLoading(false);
            return;
        }

        if (username.toLowerCase() === 'vishwa' && password === 'vishwa2005') {
            setUser({ username: 'vishwa', role: 'admin' });
            setCurrentView('admin');
            setIsLoading(false);
            return;
        }

        try {
            const q = query(collection(db, APP_CLIENTS_COLLECTION), where("username", "==", username));
            const querySnapshot = await getDocs(q);
            if (querySnapshot.empty) {
                setError('Invalid username or password.');
                setIsLoading(false);
                return;
            }
            
            let clientData = null;
            let clientId = null;
            querySnapshot.forEach(doc => {
                clientData = doc.data();
                clientId = doc.id;
            });

            if (clientData && bcrypt.compareSync(password, clientData.passwordHash)) {
                setUser({ 
                    username: clientData.username, 
                    role: 'client', 
                    clientFirebaseUid: clientData.associatedClientFirebaseUid,
                    id: clientId 
                });
                setCurrentView('client');
            } else {
                setError('Invalid username or password.');
            }
        } catch (err) {
            console.error("Login error:", err);
            setError('Login failed. Please try again.');
        }
        setIsLoading(false);
    };

    const handleLogout = () => {
        setUser(null);
        setCurrentView('login');
        setError('');
    };

    if (isLoading && !isAuthReady) {
        return <div className="min-h-screen flex items-center justify-center bg-gray-100"><div className="text-xl font-semibold">Initializing Firebase Auth...</div></div>;
    }
    if (isLoading) {
         return <div className="min-h-screen flex items-center justify-center bg-gray-100"><div className="text-xl font-semibold">Loading...</div></div>;
    }


    return (
        <div className="min-h-screen bg-gray-100 text-gray-800 font-sans">
            <header className="bg-blue-600 text-white p-4 shadow-md">
                <div className="container mx-auto flex justify-between items-center">
                    <h1 className="text-2xl font-bold">Order Tracking Portal</h1>
                    {user && (
                        <div className="flex items-center">
                            <span className="mr-4">Welcome, {user.username} ({user.role}) {firebaseAuthUser ? `(Firebase UID: ${firebaseAuthUser.uid.substring(0,6)}...)` : '(No Firebase User)'}</span>
                            <button
                                onClick={handleLogout}
                                className="bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded transition duration-150"
                            >
                                Logout
                            </button>
                        </div>
                    )}
                </div>
            </header>

            <main className="container mx-auto p-4 md:p-8">
                {error && <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4" role="alert">{error}</div>}
                
                {!user && currentView === 'login' && <LoginPage onLogin={handleLogin} isLoading={isLoading} />}
                {user?.role === 'admin' && currentView === 'admin' && <AdminDashboard db={db} authUser={firebaseAuthUser} />}
                {user?.role === 'client' && currentView === 'client' && <ClientPortal db={db} clientUser={user} authUser={firebaseAuthUser} />}
            </main>
            
            <footer className="text-center p-4 text-gray-600 mt-8">
                <p>&copy; {new Date().getFullYear()} Order Management System. Firebase App ID: {appId}</p>
                 <p className="text-xs mt-1">Firestore Client Path: {APP_CLIENTS_COLLECTION}</p>
                <p className="text-xs">Firestore Orders Path: {ORDERS_COLLECTION}</p>
            </footer>
        </div>
    );
}

function LoginPage({ onLogin, isLoading }) {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');

    const handleSubmit = (e) => {
        e.preventDefault();
        if (!username || !password) {
            console.warn("Username and password are required for login.");
            return;
        }
        onLogin(username, password);
    };

    return (
        <div className="max-w-md mx-auto bg-white p-8 rounded-lg shadow-xl">
            <h2 className="text-3xl font-bold mb-6 text-center text-blue-600">Login</h2>
            <form onSubmit={handleSubmit}>
                <div className="mb-4">
                    <label className="block text-gray-700 text-sm font-bold mb-2" htmlFor="username">
                        Username
                    </label>
                    <input
                        id="username"
                        type="text"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        className="shadow appearance-none border rounded w-full py-3 px-4 text-gray-700 leading-tight focus:outline-none focus:ring-2 focus:ring-blue-500"
                        required
                    />
                </div>
                <div className="mb-6">
                    <label className="block text-gray-700 text-sm font-bold mb-2" htmlFor="password">
                        Password
                    </label>
                    <input
                        id="password"
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        className="shadow appearance-none border rounded w-full py-3 px-4 text-gray-700 mb-3 leading-tight focus:outline-none focus:ring-2 focus:ring-blue-500"
                        required
                    />
                </div>
                <div className="flex items-center justify-between">
                    <button
                        type="submit"
                        disabled={isLoading}
                        className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-6 rounded focus:outline-none focus:shadow-outline transition duration-150 w-full disabled:opacity-50"
                    >
                        {isLoading ? 'Logging in...' : 'Login'}
                    </button>
                </div>
            </form>
        </div>
    );
}

function AdminDashboard({ db, authUser }) {
    if (!authUser) return <p className="text-red-500">Admin actions disabled: Firebase user not authenticated.</p>;

    return (
        <div className="space-y-8">
            <h2 className="text-3xl font-semibold text-center text-gray-700 mb-6">Admin Dashboard</h2>
            <div className="grid md:grid-cols-2 gap-8">
                <ClientManagement db={db} />
                <OrderManagement db={db} />
            </div>
        </div>
    );
}

function ClientManagement({ db }) {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [clientFirebaseUid, setClientFirebaseUid] = useState('');
    const [clients, setClients] = useState([]);
    const [isLoading, setIsLoading] = useState(false);
    const [feedback, setFeedback] = useState({ message: '', type: '' });
    const [showConfirmModal, setShowConfirmModal] = useState(false);
    const [clientToDelete, setClientToDelete] = useState(null);


    const fetchClients = useCallback(async () => {
        setIsLoading(true);
        try {
            const q = query(collection(db, APP_CLIENTS_COLLECTION));
            const unsubscribe = onSnapshot(q, (querySnapshot) => {
                const clientsData = [];
                querySnapshot.forEach((doc) => {
                    clientsData.push({ id: doc.id, ...doc.data() });
                });
                setClients(clientsData);
                setIsLoading(false);
            }, (err) => {
                console.error("Error fetching clients:", err);
                setFeedback({ message: 'Failed to fetch clients.', type: 'error' });
                setIsLoading(false);
            });
            return unsubscribe;
        } catch (err) {
            console.error("Error setting up client listener:", err);
            setFeedback({ message: 'Error setting up client listener.', type: 'error' });
            setIsLoading(false);
        }
    }, [db]);

    useEffect(() => {
        const unsubscribePromise = fetchClients();
        return () => { 
            Promise.resolve(unsubscribePromise).then(unsubscribe => {
                if (unsubscribe && typeof unsubscribe === 'function') {
                    unsubscribe();
                }
            });
        };
    }, [fetchClients]);


    const handleAddClient = async (e) => {
        e.preventDefault();
        if (!username || !password || !clientFirebaseUid) {
            setFeedback({ message: 'All fields are required.', type: 'error' });
            return;
        }
        if (typeof window.bcrypt === 'undefined') {
            setFeedback({ message: 'bcrypt.js is not loaded. Cannot securely add client.', type: 'error' });
            console.error("Security Alert: bcrypt.js is not loaded. Passwords will not be hashed correctly.");
            return;
        }

        setIsLoading(true);
        setFeedback({ message: '', type: '' });
        try {
            const passwordHash = bcrypt.hashSync(password, 10); 
            await addDoc(collection(db, APP_CLIENTS_COLLECTION), {
                username,
                passwordHash,
                associatedClientFirebaseUid: clientFirebaseUid,
                createdAt: Timestamp.now()
            });
            setFeedback({ message: 'Client added successfully!', type: 'success' });
            setUsername('');
            setPassword('');
            setClientFirebaseUid('');
        } catch (err) {
            console.error("Error adding client:", err);
            setFeedback({ message: `Failed to add client: ${err.message}`, type: 'error' });
        }
        setIsLoading(false);
    };

    const confirmDeleteClient = (clientId) => {
        setClientToDelete(clientId);
        setShowConfirmModal(true);
    };

    const executeDeleteClient = async () => {
        if (!clientToDelete) return;
        setIsLoading(true);
        setShowConfirmModal(false);
        try {
            await deleteDoc(doc(db, APP_CLIENTS_COLLECTION, clientToDelete));
            setFeedback({ message: 'Client deleted successfully!', type: 'success' });
        } catch (err) {
            console.error("Error deleting client:", err);
            setFeedback({ message: `Failed to delete client: ${err.message}`, type: 'error' });
        }
        setIsLoading(false);
        setClientToDelete(null);
    };


    return (
        <div className="bg-white p-6 rounded-lg shadow-lg">
            <h3 className="text-xl font-semibold mb-4 text-gray-700">Manage Clients</h3>
            {feedback.message && (
                <div className={`p-3 mb-4 rounded text-sm ${feedback.type === 'success' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
                    {feedback.message}
                </div>
            )}
            <form onSubmit={handleAddClient} className="space-y-4 mb-6">
                <div>
                    <label className="block text-sm font-medium text-gray-700">Client Username</label>
                    <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} required className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm" />
                </div>
                <div>
                    <label className="block text-sm font-medium text-gray-700">Client Password</label>
                    <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm" />
                </div>
                <div>
                    <label className="block text-sm font-medium text-gray-700">Client's Firebase UID (for order tracking)</label>
                    <input type="text" value={clientFirebaseUid} onChange={(e) => setClientFirebaseUid(e.target.value)} required className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm" placeholder="e.g., JE0NxF0yiodRBICC0eV6Z1pL3Sl1" />
                </div>
                <button type="submit" disabled={isLoading} className="w-full bg-green-500 hover:bg-green-600 text-white font-semibold py-2 px-4 rounded-md shadow-sm disabled:opacity-50 transition duration-150">
                    {isLoading ? 'Adding Client...' : 'Add Client'}
                </button>
            </form>
            <h4 className="text-lg font-medium mb-2 text-gray-600">Existing Clients</h4>
            {isLoading && clients.length === 0 && <p>Loading clients...</p>}
            {!isLoading && clients.length === 0 && <p className="text-gray-500">No clients added yet.</p>}
            <ul className="space-y-2 max-h-60 overflow-y-auto">
                {clients.map(client => (
                    <li key={client.id} className="flex justify-between items-center p-3 bg-gray-50 rounded-md border border-gray-200">
                        <div>
                            <p className="font-medium text-gray-800">{client.username}</p>
                            <p className="text-xs text-gray-500">Firebase UID: {client.associatedClientFirebaseUid}</p>
                        </div>
                        <button 
                            onClick={() => confirmDeleteClient(client.id)}
                            disabled={isLoading}
                            className="text-red-500 hover:text-red-700 text-sm font-medium disabled:opacity-50"
                        >
                            Delete
                        </button>
                    </li>
                ))}
            </ul>
            {showConfirmModal && (
                <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
                    <div className="bg-white p-6 rounded-lg shadow-xl max-w-sm w-full">
                        <h4 className="text-lg font-semibold mb-4">Confirm Deletion</h4>
                        <p className="mb-4 text-sm text-gray-700">Are you sure you want to delete this client? This action cannot be undone.</p>
                        <div className="flex justify-end space-x-3">
                            <button onClick={() => setShowConfirmModal(false)} className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-200 hover:bg-gray-300 rounded-md">Cancel</button>
                            <button onClick={executeDeleteClient} className="px-4 py-2 text-sm font-medium text-white bg-red-600 hover:bg-red-700 rounded-md">Delete</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

function OrderManagement({ db }) {
    const [orders, setOrders] = useState([]);
    const [clients, setClients] = useState([]); 
    
    const [selectedClientUid, setSelectedClientUid] = useState('');
    const [itemName, setItemName] = useState('');
    const [quantity, setQuantity] = useState(1);
    const [adminNotes, setAdminNotes] = useState('');

    const [isLoading, setIsLoading] = useState(false);
    const [feedback, setFeedback] = useState({ message: '', type: '' });
    const [showDeleteOrderModal, setShowDeleteOrderModal] = useState(false);
    const [orderToDelete, setOrderToDelete] = useState(null);


    const orderStatuses = ["Pending", "Processing", "Shipped", "Delivered", "Cancelled"];

    useEffect(() => {
        const fetchClientsForOrders = async () => {
            try {
                const q = query(collection(db, APP_CLIENTS_COLLECTION));
                const unsubscribe = onSnapshot(q, (querySnapshot) => {
                    const clientsData = [];
                    querySnapshot.forEach((doc) => {
                        clientsData.push({ id: doc.id, username: doc.data().username, firebaseUid: doc.data().associatedClientFirebaseUid });
                    });
                    setClients(clientsData);
                    if (clientsData.length > 0 && !selectedClientUid) {
                    }
                });
                return unsubscribe;
            } catch (err) {
                console.error("Error fetching clients for orders:", err);
                setFeedback({ message: 'Failed to fetch clients for order creation.', type: 'error' });
            }
        };
        const unsubscribePromise = fetchClientsForOrders();
         return () => {
            Promise.resolve(unsubscribePromise).then(unsubscribe => {
                if (unsubscribe && typeof unsubscribe === 'function') {
                    unsubscribe();
                }
            });
        };
    }, [db]);

    useEffect(() => {
        setIsLoading(true);
        const q = query(collection(db, ORDERS_COLLECTION)); 
        const unsubscribe = onSnapshot(q, (querySnapshot) => {
            const ordersData = [];
            querySnapshot.forEach((doc) => {
                ordersData.push({ id: doc.id, ...doc.data() });
            });
            ordersData.sort((a, b) => (b.createdAt?.toMillis() || 0) - (a.createdAt?.toMillis() || 0));
            setOrders(ordersData);
            setIsLoading(false);
        }, (err) => {
            console.error("Error fetching orders:", err);
            setFeedback({ message: 'Failed to fetch orders.', type: 'error' });
            setIsLoading(false);
        });
        return () => unsubscribe();
    }, [db]);

    const handleAddOrder = async (e) => {
        e.preventDefault();
        if (!selectedClientUid || !itemName || quantity < 1) {
            setFeedback({ message: 'Client, item name, and valid quantity are required.', type: 'error' });
            return;
        }
        setIsLoading(true);
        setFeedback({ message: '', type: '' });
        try {
            await addDoc(collection(db, ORDERS_COLLECTION), {
                clientFirebaseUid: selectedClientUid,
                itemName,
                quantity: Number(quantity),
                status: "Pending", 
                adminNotes,
                createdAt: Timestamp.now(),
                lastUpdatedAt: Timestamp.now()
            });
            setFeedback({ message: 'Order added successfully!', type: 'success' });
            setItemName('');
            setQuantity(1);
            setAdminNotes('');
            setSelectedClientUid('');
        } catch (err) {
            console.error("Error adding order:", err);
            setFeedback({ message: `Failed to add order: ${err.message}`, type: 'error' });
        }
        setIsLoading(false);
    };

    const handleUpdateOrderStatus = async (orderId, newStatus) => {
        setIsLoading(true);
        try {
            const orderRef = doc(db, ORDERS_COLLECTION, orderId);
            await updateDoc(orderRef, {
                status: newStatus,
                lastUpdatedAt: Timestamp.now()
            });
            setFeedback({ message: 'Order status updated!', type: 'success' });
        } catch (err) {
            console.error("Error updating order status:", err);
            setFeedback({ message: `Failed to update status: ${err.message}`, type: 'error' });
        }
        setIsLoading(false);
    };
    
    const confirmDeleteOrder = (orderId) => {
        setOrderToDelete(orderId);
        setShowDeleteOrderModal(true);
    };

    const executeDeleteOrder = async () => {
        if (!orderToDelete) return;
        setIsLoading(true);
        setShowDeleteOrderModal(false);
        try {
            await deleteDoc(doc(db, ORDERS_COLLECTION, orderToDelete));
            setFeedback({ message: 'Order deleted successfully!', type: 'success' });
        } catch (err) {
            console.error("Error deleting order:", err);
            setFeedback({ message: `Failed to delete order: ${err.message}`, type: 'error' });
        }
        setIsLoading(false);
        setOrderToDelete(null);
    };


    return (
        <div className="bg-white p-6 rounded-lg shadow-lg">
            <h3 className="text-xl font-semibold mb-4 text-gray-700">Manage Orders</h3>
             {feedback.message && (
                <div className={`p-3 mb-4 rounded text-sm ${feedback.type === 'success' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
                    {feedback.message}
                </div>
            )}

            <form onSubmit={handleAddOrder} className="space-y-4 mb-6 p-4 border border-gray-200 rounded-md">
                <h4 className="text-lg font-medium text-gray-600">Add New Order</h4>
                <div>
                    <label className="block text-sm font-medium text-gray-700">Client</label>
                    <select value={selectedClientUid} onChange={(e) => setSelectedClientUid(e.target.value)} required className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
                        <option value="">Select Client</option>
                        {clients.map(client => (
                            <option key={client.id} value={client.firebaseUid}>{client.username} ({client.firebaseUid.substring(0,6)}...)</option>
                        ))}
                    </select>
                </div>
                 <div>
                    <label className="block text-sm font-medium text-gray-700">Item Name</label>
                    <input type="text" value={itemName} onChange={(e) => setItemName(e.target.value)} required className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm" />
                </div>
                <div>
                    <label className="block text-sm font-medium text-gray-700">Quantity</label>
                    <input type="number" min="1" value={quantity} onChange={(e) => setQuantity(e.target.value)} required className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm" />
                </div>
                <div>
                    <label className="block text-sm font-medium text-gray-700">Admin Notes (Optional)</label>
                    <textarea value={adminNotes} onChange={(e) => setAdminNotes(e.target.value)} rows="2" className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"></textarea>
                </div>
                <button type="submit" disabled={isLoading || clients.length === 0} className="w-full bg-blue-500 hover:bg-blue-600 text-white font-semibold py-2 px-4 rounded-md shadow-sm disabled:opacity-50 transition duration-150">
                    {isLoading ? 'Adding Order...' : (clients.length === 0 ? 'Add a client first' : 'Add Order')}
                </button>
            </form>

            <h4 className="text-lg font-medium mb-2 text-gray-600">All Orders</h4>
            {isLoading && orders.length === 0 && <p>Loading orders...</p>}
            {!isLoading && orders.length === 0 && <p className="text-gray-500">No orders placed yet.</p>}
            <div className="space-y-3 max-h-96 overflow-y-auto">
                {orders.map(order => (
                    <div key={order.id} className="p-4 bg-gray-50 rounded-md border border-gray-200">
                        <div className="flex justify-between items-start">
                            <div>
                                <p className="font-semibold text-gray-800">{order.itemName} (Qty: {order.quantity})</p>
                                <p className="text-xs text-gray-500">Order ID: {order.id}</p>
                                <p className="text-xs text-gray-500">Client UID: {order.clientFirebaseUid}</p>
                                {order.adminNotes && <p className="text-xs text-gray-500 mt-1">Notes: {order.adminNotes}</p>}
                            </div>
                             <button 
                                onClick={() => confirmDeleteOrder(order.id)}
                                disabled={isLoading}
                                className="text-red-400 hover:text-red-600 text-xs font-medium disabled:opacity-50 ml-2"
                            >
                                Delete Order
                            </button>
                        </div>
                        <div className="mt-2 flex items-center">
                            <label className="text-sm font-medium text-gray-700 mr-2">Status:</label>
                            <select 
                                value={order.status} 
                                onChange={(e) => handleUpdateOrderStatus(order.id, e.target.value)}
                                disabled={isLoading}
                                className="block w-full md:w-auto px-3 py-1.5 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm disabled:opacity-70"
                            >
                                {orderStatuses.map(status => (
                                    <option key={status} value={status}>{status}</option>
                                ))}
                            </select>
                        </div>
                        <p className="text-xs text-gray-400 mt-1">Last Updated: {order.lastUpdatedAt?.toDate().toLocaleString()}</p>
                    </div>
                ))}
            </div>
            {showDeleteOrderModal && (
                 <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
                    <div className="bg-white p-6 rounded-lg shadow-xl max-w-sm w-full">
                        <h4 className="text-lg font-semibold mb-4">Confirm Order Deletion</h4>
                        <p className="mb-4 text-sm text-gray-700">Are you sure you want to delete this order? This action cannot be undone.</p>
                        <div className="flex justify-end space-x-3">
                            <button onClick={() => setShowDeleteOrderModal(false)} className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-200 hover:bg-gray-300 rounded-md">Cancel</button>
                            <button onClick={executeDeleteOrder} className="px-4 py-2 text-sm font-medium text-white bg-red-600 hover:bg-red-700 rounded-md">Delete Order</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

function ClientPortal({ db, clientUser, authUser }) {
    const [orders, setOrders] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState('');

    useEffect(() => {
        if (!clientUser || !clientUser.clientFirebaseUid) {
            setError("Client information is missing.");
            setIsLoading(false);
            return;
        }
        if (!authUser) {
             setError("Client portal disabled: Firebase user not authenticated.");
             setIsLoading(false);
            return;
        }

        setIsLoading(true);
        setError('');
        const q = query(collection(db, ORDERS_COLLECTION), where("clientFirebaseUid", "==", clientUser.clientFirebaseUid));
        
        const unsubscribe = onSnapshot(q, (querySnapshot) => {
            const clientOrders = [];
            querySnapshot.forEach((doc) => {
                clientOrders.push({ id: doc.id, ...doc.data() });
            });
            clientOrders.sort((a, b) => (b.createdAt?.toMillis() || 0) - (a.createdAt?.toMillis() || 0));
            setOrders(clientOrders);
            setIsLoading(false);
        }, (err) => {
            console.error("Error fetching client orders:", err);
            setError('Failed to fetch your orders. Please try again later.');
            setIsLoading(false);
        });

        return () => unsubscribe();
    }, [db, clientUser, authUser]);

    if (!clientUser) return <p className="text-center text-red-500">Error: Client data not loaded.</p>;
    if (!authUser) return <p className="text-center text-red-500">Error: Firebase auth not ready.</p>;


    return (
        <div className="bg-white p-6 md:p-8 rounded-lg shadow-xl">
            <h2 className="text-3xl font-semibold text-center text-gray-700 mb-8">Your Orders</h2>
            {error && <p className="text-red-500 bg-red-100 p-3 rounded mb-4">{error}</p>}
            {isLoading && <p className="text-center text-gray-600">Loading your orders...</p>}
            {!isLoading && orders.length === 0 && <p className="text-center text-gray-500">You have no orders yet.</p>}
            
            {!isLoading && orders.length > 0 && (
                <div className="space-y-6">
                    {orders.map(order => (
                        <div key={order.id} className="p-6 bg-gray-50 rounded-lg border border-gray-200 shadow-sm hover:shadow-md transition-shadow">
                            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-2">
                                <h3 className="text-xl font-semibold text-blue-600">{order.itemName}</h3>
                                <span className={`px-3 py-1 text-sm font-medium rounded-full ${
                                    order.status === "Delivered" ? "bg-green-100 text-green-700" :
                                    order.status === "Shipped" ? "bg-blue-100 text-blue-700" :
                                    order.status === "Processing" ? "bg-yellow-100 text-yellow-700" :
                                    order.status === "Cancelled" ? "bg-red-100 text-red-700" :
                                    "bg-gray-100 text-gray-700"
                                }`}>
                                    {order.status}
                                </span>
                            </div>
                            <p className="text-gray-600">Quantity: {order.quantity}</p>
                            {order.adminNotes && <p className="text-sm text-gray-500 mt-1">Notes from Admin: {order.adminNotes}</p>}
                            <div className="mt-3 text-xs text-gray-400">
                                <p>Order ID: {order.id}</p>
                                <p>Placed on: {order.createdAt?.toDate().toLocaleDateString()}</p>
                                <p>Last Updated: {order.lastUpdatedAt?.toDate().toLocaleString()}</p>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}

export default App;
