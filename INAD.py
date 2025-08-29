
import time
import random
import logging
import numpy as np
import pandas as pd
from typing import List, Dict
from sklearn.model_selection import train_test_split
from sklearn.feature_selection import RFE
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import accuracy_score, f1_score

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("INAD")

CLASSIFIERS = {
    "DT": DecisionTreeClassifier(),
    "SVM": SVC(probability=True),
    "RF": RandomForestClassifier(),
    "kNN": KNeighborsClassifier(),
    "GBT": GradientBoostingClassifier(),
    "NB": GaussianNB()
}

Classifier_Weights: Dict[str, float] = {}
Selected_Features: List[str] = []
Threshold: float = 0.5



def initialize_inad():
    logger.info("INAD Initialized. Ready to process network traffic.")



def perform_feature_selection(X: pd.DataFrame, y: pd.Series) -> List[str]:
    estimator = RandomForestClassifier()
    selector = RFE(estimator, n_features_to_select=min(10, X.shape[1]))
    selector.fit(X, y)
    selected = list(X.columns[selector.support_])
    logger.info(f"Selected Features: {selected}")
    return selected



def train_classifiers(X: pd.DataFrame, y: pd.Series) -> Dict[str, float]:
    weights = {}
    performance = {}

    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)

    for name, model in CLASSIFIERS.items():
        model.fit(X_train, y_train)
        preds = model.predict(X_val)
        f1 = f1_score(y_val, preds, pos_label="DDoS Attack", average='binary')
        performance[name] = f1
        logger.info(f"{name} F1-Score: {f1:.4f}")

    total = sum(performance.values())
    for name in CLASSIFIERS:
        weights[name] = performance[name] / total if total else 1.0 / len(CLASSIFIERS)

    logger.info(f"Classifier Weights: {weights}")
    return weights



def predict_label(instance: pd.DataFrame) -> float:
    weighted_votes = 0.0
    for name, model in CLASSIFIERS.items():
        prediction = model.predict(instance)[0]
        weighted_votes += Classifier_Weights[name] * (1 if prediction == "DDoS Attack" else 0)
    return weighted_votes



def classify_instance(instance: pd.DataFrame) -> str:
    score = predict_label(instance)
    result = "DDoS Attack" if score > Threshold else "Normal"
    logger.info(f"Traffic Classified as: {result} (Score: {score:.3f})")
    return result



def evaluate_system(test_df: pd.DataFrame):
    X_test = test_df[Selected_Features]
    y_test = test_df["label"]
    predictions = []

    for i in range(len(X_test)):
        instance = X_test.iloc[[i]]
        prediction = classify_instance(instance)
        predictions.append(prediction)

    acc = accuracy_score(y_test, predictions)
    f1 = f1_score(y_test, predictions, pos_label="DDoS Attack", average='binary')
    logger.info(f"Evaluation Accuracy: {acc:.4f}, F1-Score: {f1:.4f}")



def simulate_p4_traffic_batch() -> pd.DataFrame:
    row_count = 5
    features = Selected_Features or [f"f{i}" for i in range(10)]
    data = np.random.rand(row_count, len(features))
    return pd.DataFrame(data, columns=features)



def run_inad_pipeline(labeled_data: pd.DataFrame, test_data: pd.DataFrame, decision_threshold: float = 0.5):
    global Classifier_Weights, Selected_Features, Threshold
    Threshold = decision_threshold

    initialize_inad()

    X = labeled_data.drop(columns=["label"])
    y = labeled_data["label"]
    Selected_Features = perform_feature_selection(X, y)

    Classifier_Weights = train_classifiers(X[Selected_Features], y)

    start_time = time.time()
    loop_duration = 10  
    while time.time() - start_time < loop_duration:
        batch = simulate_p4_traffic_batch()
        for i in range(len(batch)):
            instance = batch.iloc[[i]]
            classify_instance(instance)
        time.sleep(1)

    evaluate_system(test_data)


if __name__ == "__main__":
    feature_names = [f"f{i}" for i in range(10)]
    data_size = 100
    df = pd.DataFrame(np.random.rand(data_size, 10), columns=feature_names)
    df["label"] = np.random.choice(["DDoS Attack", "Normal"], size=data_size, p=[0.3, 0.7])

    test_df = pd.DataFrame(np.random.rand(20, 10), columns=feature_names)
    test_df["label"] = np.random.choice(["DDoS Attack", "Normal"], size=20, p=[0.3, 0.7])

    run_inad_pipeline(df, test_df, decision_threshold=0.6)