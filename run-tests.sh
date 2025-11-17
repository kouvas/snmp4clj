#!/bin/bash
# Simple test runner script for environments with basic Clojure

set -e

# Create a temporary directory for our deps
CACHE_DIR=".cpcache"
mkdir -p "$CACHE_DIR"

# Function to download a JAR from Maven Central
download_jar() {
    local group=$1
    local artifact=$2
    local version=$3
    local group_path=$(echo "$group" | tr '.' '/')
    local jar_name="${artifact}-${version}.jar"
    local local_path="$CACHE_DIR/${jar_name}"

    if [ ! -f "$local_path" ]; then
        echo "Downloading $artifact $version..."
        wget -q -O "$local_path" \
            "https://repo1.maven.org/maven2/${group_path}/${artifact}/${version}/${jar_name}" || \
            curl -s -L -o "$local_path" \
                "https://repo1.maven.org/maven2/${group_path}/${artifact}/${version}/${jar_name}"
    fi

    echo "$local_path"
}

# Download required test dependencies
TESTCHECK_JAR=$(download_jar "org.clojure" "test.check" "1.1.1")

# For test-runner from git, we'll need to handle differently
# Let's just run tests manually using clojure.test

# Build classpath
CP="src:test:$TESTCHECK_JAR"

echo "Running tests..."
clojure -cp "$CP" -e "
(require '[clojure.test :as t])
(require '[clojure.java.io :as io])

;; Find and load all test namespaces
(doseq [file (file-seq (io/file \"test\"))]
  (when (and (.isFile file)
             (.endsWith (.getName file) \".clj\")
             (not (.contains (.getPath file) \"integration\")))
    (let [ns-name (-> (.getPath file)
                      (subs 5)  ;; remove 'test/'
                      (.replace \"/\" \".\")
                      (.replace \"_\" \"-\")
                      (.replace \".clj\" \"\"))]
      (try
        (require (symbol ns-name))
        (println \"Loaded:\" ns-name)
        (catch Exception e
          (println \"Failed to load:\" ns-name (.getMessage e)))))))

;; Run all tests
(let [results (t/run-all-tests #\"^kouvas\..*\")]
  (System/exit (if (and (zero? (:fail results 0))
                        (zero? (:error results 0)))
                   0
                   1)))
"
